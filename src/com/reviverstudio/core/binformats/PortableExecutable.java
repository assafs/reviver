/**
 * PortableExecutable is in charge of all PE specific operations.
 *
 * In this iteration, it is only a concrete class, which will supply the
 * foundations for a proper IBinaryFile interface
 */

package com.reviverstudio.core.binformats;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import java.math.BigInteger;

/**
 *
 * @author assafs
 */
public class PortableExecutable
{
    public enum Machine {
        I386,
        IA64,
        AMD64
    }
    
    public static class NtHeader
    {
        private static final short DOS_SIGNATURE = 0x5A4D;       // 'MZ'

        private static final int e_lfanew_offset = 0x3C;

        private static final int NT_SIGNATURE = 0x00004550;     // PE00

        private final short OPTIONAL32_MAGIC = 0x10b;             // 32-bit PE
        private final short OPTIONAL64_MAGIC = 0x20b;             // 64-bit PE

        private final int MACHINE_I386 = 0x014c;
        private final int MACHINE_IA64 = 0x0200;
        private final int MACHINE_AMD64 = 0x8664;

        // the exact value will be decided during runtime, based on PE parameters
        private int DIRECTORIES_OFFSET = 0x60;

        //
        // these offsets are offsets based on the DirectoriesOffset, and will
        // be updated in run time.
        private int RVAS_OFFSET = -4;


        public enum OptHeaderType
        {
            OPT32,
            OPT64
        }

        /* FileHeader fields */

        Machine _machine;
        int _numOfSections;
        Date _timestamp;
        int _optHeaderSize;

        OptHeaderType _optHeaderType;
        
        BigInteger _codeSize;
        BigInteger _dataBase;
        BigInteger _codeBase;

        BigInteger _entryPoint;
        
        BigInteger _imageBase;

        int _fileAlignment;
        int _sectionAlignment;

        void setOptHeaderType(int t) throws BinaryFormatException
        {
            switch (t)
            {
                case OPTIONAL32_MAGIC:
                    _optHeaderType = OptHeaderType.OPT32;
                    break;
                case OPTIONAL64_MAGIC:
                    _optHeaderType = OptHeaderType.OPT64;
                    break;
                default:
                    throw new BinaryFormatException(BinaryFormatException.Code.InvalidOptionalMagic);
            }
        }

        /**
         * Sets and validates the architecture for the PE file
         * 
         * @param m the new architecture
         * @throws BinaryFormatException bad arch specified
         */
        void setMachine(int m) throws BinaryFormatException
        {
            switch (m)
            {
                case MACHINE_I386:
                    _machine = Machine.I386;
                    break;
                case MACHINE_IA64:
                    _machine = Machine.IA64;
                    break;
                case MACHINE_AMD64:
                    _machine = Machine.AMD64;
                    break;
                default:
                    throw new BinaryFormatException(BinaryFormatException.Code.BadArch);
            }
        }

        Machine getMachine()
        {
            return _machine;
        }

        void setTimeStamp(int ts)
        {
            _timestamp = new Date(ts * 1000L);
        }

        Date getTimeStamp()
        {
            return _timestamp;
        }
        
        private ByteBuffer _buffer;

        /**
         * get the offset to the NT header
         *
         * @return offset to the NT header
         * @throws IOException on bad file access (usually means the file is cropped)
         * @throws BinaryFormatException on bad header signature
         */
        private int getNtOffset() throws IOException, BinaryFormatException
        {
            short magic = _buffer.asShortBuffer().get();

            if (magic != DOS_SIGNATURE)
            {
                throw new BinaryFormatException(BinaryFormatException.Code.InvalidMZHeader);
            }

            return _buffer.getInt(e_lfanew_offset);
        }

        private void initOptional32_ImageBase()
        {
            byte[] intBuf = new byte[4];

            _buffer.get(intBuf);
            _dataBase = new BigInteger(intBuf);

            _buffer.get(intBuf);
            _imageBase = new BigInteger(intBuf);
        }

        private void initOptional64_ImageBase()
        {
            _dataBase = BigInteger.ZERO;

            byte[] longBuf = new byte[8];
            _buffer.get(longBuf);

            _imageBase = new BigInteger(longBuf);
        }


        /**
         * Initialize a new NtHeader based on the passed buffer.
         *
         * It is assumed that the buffer already points at the start of the PE, regardless of the
         * position in the file.
         *
         * Upon returning, the buffer is positioned at the end of the header.
         *
         * @param buf the input buffer
         * @throws IOException reading errors from the buffer
         * @throws BinaryFormatException bad format in the PE itself
         */
        public NtHeader(ByteBuffer buf) throws IOException, BinaryFormatException
        {
            _buffer = buf;
            _buffer.order(ByteOrder.LITTLE_ENDIAN);

            // skip the MZ header, and start processing the PE header
            _buffer.position(getNtOffset());

            // the this location will be used often later on, so mark it
            _buffer.mark();

            
            if (buf.getInt() != NT_SIGNATURE)
            {
                throw new BinaryFormatException(BinaryFormatException.Code.InvalidPEHeader);
            }

            // process file header
            initFileHeader();
            initOptionalHeader();

            // set the buffer to the end of the optional header
            _buffer.position(_optHeaderSize);
        }

        private void initFileHeader() throws BinaryFormatException, IOException
        {
            setMachine(_buffer.getShort());
            _numOfSections = _buffer.getShort();
            setTimeStamp(_buffer.getInt());
          
            // pointer to symbols
            _buffer.getInt();

            // num of symbols
            _buffer.getInt();

            // size of optional
            _optHeaderSize = _buffer.getShort();

            // characteristics
            _buffer.getShort();
        }

        private void initOptionalHeader() throws BinaryFormatException, IOException
        {
            setOptHeaderType(_buffer.getShort());

            if (_optHeaderType == OptHeaderType.OPT64)
            {
                DIRECTORIES_OFFSET += 0x10;
            }


            // read (and ignore) Linker version
            _buffer.getInt();

                        byte[] intBuf = new byte[4];
            _buffer.get(intBuf);
            _codeSize = new BigInteger(intBuf);
                    

            // size of initialized and uninitialized data (ignored)
            _buffer.getInt();
            _buffer.getInt();


            _buffer.get(intBuf);
            _entryPoint = new BigInteger(intBuf);

            _buffer.get(intBuf);
            _codeBase = new BigInteger(intBuf);
            _buffer.get(intBuf);
            _dataBase = new BigInteger(intBuf);

            switch (_optHeaderType)
            {
                case OPT32:
                    initOptional32_ImageBase();
                    break;
                case OPT64:
                    initOptional64_ImageBase();
                    break;
            }

            //
            // decrease by 1 to create an alignment mask
            _sectionAlignment = _buffer.getInt() - 1;
            _fileAlignment = _buffer.getInt() - 1;
        }
    }


    /**
     * Original filename used to create this object
     */
    String          _filename;

    /**
     * Read-only channel for this file
     */
    FileChannel     _roChannel;

    ByteBuffer      _baseBuffer;

    NtHeader        _header;


    /**
     * Initialize a new Portable Executable from the specified file.
     *
     * The PE will be mapped into memory, and parsed into its sections
     *
     * @param filename the file to process
     * @throws IOException upon IO errors in the underlying file
     * @throws BinaryFormatException for unsupported values in the PE file
     */
    public PortableExecutable(String filename) throws IOException, BinaryFormatException
    {
        File file = new File(filename);

        _roChannel = new RandomAccessFile(file, "r").getChannel();
        _baseBuffer = _roChannel.map(FileChannel.MapMode.READ_ONLY, 0, _roChannel.size());

        _baseBuffer.mark();
        _header = new NtHeader(_baseBuffer);
    }

    void initSsections()
    {
        
    }
}
