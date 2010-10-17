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
import java.math.*;


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

    private static void reverseByteArray(byte[] array)
    {
        int i, j;
        byte temp;

        for (i = 0, j = array.length - 1; i < j; i++, j--) {
            temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }

    private static BigInteger getBigInt(ByteBuffer buffer)
    {
        byte[] bytes = new byte[4];
        buffer.get(bytes);

        reverseByteArray(bytes);

        return new BigInteger(bytes);
    }

    private static BigInteger getBigLong(ByteBuffer buffer)
    {
        byte[] bytes = new byte[8];
        buffer.get(bytes);

        reverseByteArray(bytes);

        return new BigInteger(bytes);
    }


    public static class PEDirectory
    {
        public BigInteger offset;
        public BigInteger size;

        public PEDirectory(ByteBuffer buf) throws IOException
        {
            byte[] intBuf = new byte[4];

            buf.get(intBuf);
            offset = new BigInteger(intBuf);

            buf.get(intBuf);
            size = new BigInteger(intBuf);
        }
    }
    
    public static class PEHeader
    {
        static final short DOS_SIGNATURE = 0x5A4D;       // 'MZ'

        static final int e_lfanew_offset = 0x3C;

        static final int NT_SIGNATURE = 0x00004550;     // PE00

        final short OPTIONAL32_MAGIC = 0x10b;             // 32-bit PE
        final short OPTIONAL64_MAGIC = 0x20b;             // 64-bit PE

        final short OPTIONAL32_SIZE = 0x00f8;
        final short OPTIONAL64_SIZE = 0x0108;

        final int MACHINE_I386 = 0x014c;
        final int MACHINE_IA64 = 0x0200;
        final int MACHINE_AMD64 = 0x8664;

        final int FILE_HEADER_SIZE = 0x18;
 
        final int DIRECTORY_EXPORT = 0;
        final int DIRECTORY_IMPORT = 1;
        final int DIRECTORY_RESOURCE = 2;
        final int DIRECTORY_EXCEPTION = 3;
        final int DIRECTORY_SECURITY = 4;
        final int DIRECTORY_BASERELOC = 5;
        final int DIRECTORY_DEBUG = 6;
        final int DIRECTORY_ARCHITECTURE = 7;
        final int DIRECTORY_GLOBALPTR = 8;
        final int DIRECTORY_TLS = 9;
        final int DIRECTORY_LOAD_CONFIG = 10;
        final int DIRECTORY_BOUND_IMPORT = 11;
        final int DIRECTORY_IAT = 12;
        final int DIRECTORY_DELAY_IMPORT = 13;
        final int DIRECTORY_COM_DESC = 14;
        final int DIRECTORY_xxx = 15;

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

        BigInteger _stackReserveSize;
        BigInteger _stackCommitSize;
        BigInteger _heapReserveSize;
        BigInteger _heapCommitSize;

        PEDirectory[] _directories;
        
        long _sizeOfImage;
        long _sizeOfHeaders;

        int _loaderFlags;
        int _numOfRVAs;

        BigInteger _fileAlignment;
        BigInteger _sectionAlignment;

        ByteBuffer _buffer;

        /** 
         * marks the offset from the beginning of the file to the beginning of the
         * PE header.
         * 
         * 0 can never be a valid value, since the file must begin with the MZ signature.
         */
        int _peOffset = 0;

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

        public Machine getMachine()
        {
            return _machine;
        }

        public BigInteger getImageBase()
        {
            return _imageBase;
        }

        void setTimeStamp(int ts)
        {
            _timestamp = new Date(ts * 1000L);
        }

        public Date getTimeStamp()
        {
            return _timestamp;
        }

        public int getOptHeaderSize()
        {
            return _optHeaderSize;
        }

        public int getNumOfSections()
        {
            return _numOfSections;
        }

        public int getEndPos()
        {
            return _peOffset + _optHeaderSize + FILE_HEADER_SIZE;
        }

        public BigInteger getEntryPoint()
        {
            return _entryPoint;
        }

        public BigInteger getDataBase()
        {
            return _dataBase;
        }

        public BigInteger getCodeBase()
        {
            return _codeBase;
        }


        /**
         * get the offset to the NT header
         *
         * @return offset to the NT header
         * @throws IOException on bad file access (usually means the file is cropped)
         * @throws BinaryFormatException on bad header signature
         */
        public int getNtOffset() throws IOException, BinaryFormatException
        {
            if (_peOffset > 0)
            {
                return _peOffset;
            }

            short magic = _buffer.asShortBuffer().get();

            if (magic != DOS_SIGNATURE)
            {
                throw new BinaryFormatException(BinaryFormatException.Code.InvalidMZHeader);
            }

            _peOffset =  _buffer.getInt(e_lfanew_offset);
            return _peOffset;
        }

        /**
         * Initialize a new PEHeader based on the passed buffer.
         *
         * It is assumed that the buffer already points at the start of the PE, regardless of the
         * position in the file.
         *
         * Upon returning, the buffer is positioned at the end of the header.
         *
         * @param buf the input buffer
         * @throws BinaryFormatException bad format in the PE itself
         * @throws IOException reading errors from the buffer
         */
        public PEHeader(ByteBuffer buf) throws BinaryFormatException, IOException
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
            ByteBuffer header = _buffer.slice().order(ByteOrder.LITTLE_ENDIAN);
           
            setOptHeaderType(header.getShort());

            //
            // sometimes the optional header is of an invalid length
            // read as much as we can from the file, up to the actual size of the
            // header.
            if (_optHeaderType == OptHeaderType.OPT64)
            {
                header.limit(Math.min(OPTIONAL64_SIZE, header.capacity()));
            }
            else
            {
                header.limit(Math.min(OPTIONAL32_SIZE, header.capacity()));
            }


            // read (and ignore) Linker version
            header.getShort();

            _codeSize = getBigInt(header);        

            // size of initialized and uninitialized data (ignored)
            header.getInt();
            header.getInt();

            _entryPoint = getBigInt(header);
            _codeBase = getBigInt(header);

            switch (_optHeaderType)
            {
                case OPT32:
                    _dataBase = getBigInt(header);
                    _imageBase = getBigInt(header);
                    break;
                case OPT64:
                    _dataBase = BigInteger.ZERO;
                    _imageBase = getBigLong(header);
                    break;
            }

            //
            // decrease by 1 to create an alignment mask
            _sectionAlignment = getBigInt(header).subtract(BigInteger.ONE);
            _fileAlignment = getBigInt(header).subtract(BigInteger.ONE);

            // OS version
            header.getInt();
            
            // Image version
            header.getInt();

            // Subsystem
            header.getInt();

            // Win32 version
            header.getInt();

            _sizeOfImage = header.getInt();
            _sizeOfHeaders = header.getInt();

            // checksum
            header.getInt();

            // subsystem
            header.getShort();

            // Dll characteristics
            header.getShort();
            
            // read the additional information
            // if we're in 64bit mode, re-alloc the buffer since we're now
            // dealing with QWORDS but the logic remains the same
            if (_optHeaderType == OptHeaderType.OPT64)
            {
                _stackReserveSize = getBigLong(header);
                _stackCommitSize = getBigLong(header);
                _heapReserveSize = getBigLong(header);
                _heapCommitSize = getBigLong(header);

            }
            else
            {
                _stackReserveSize = getBigInt(header);
                _stackCommitSize = getBigInt(header);
                _heapReserveSize = getBigInt(header);
                _heapCommitSize = getBigInt(header);
            }

            _loaderFlags = header.getInt();
            _numOfRVAs = header.getInt();


            // if the number of RVAs is a sane value, treat it like a valid
            // entry and attempt to read as much entries from the directories
            if (_numOfRVAs <= 0 || _numOfRVAs > DIRECTORY_xxx)
            {
                return;
            }

            _directories = new PEDirectory[_numOfRVAs];

            _buffer.position(_buffer.position() + header.position());
            for (int i = 0; i < _numOfRVAs; ++i)
            {
                try
                {
                    _directories[i] = new PEDirectory(_buffer);
                }
                catch (Exception e)
                {
                    // suppressed
                    return;
                }
            }
        }
    }

    public static class PESection
    {
        public final int SECTION_SIZE = 0x28;

        private final int SECTION_NAME_LENGTH = 8;
        
        private String _name;
        
        BigInteger _virtualSize;
        BigInteger _virtualAddress;
        BigInteger _sizeOfRawData;
        BigInteger _ptrToRawData;
        BigInteger _ptrToRelocs;
        BigInteger _ptrToLineNos;

        int _numOfRelocs;
        int _numOfLineNos;

        int _characteristics;

        public String getName()
        {
            return _name;
        }

        public PESection(ByteBuffer buf)
        {
            byte[] name = new byte[SECTION_NAME_LENGTH];
            buf.get(name);

            if (name[0] == '/')
            {
                // BUGBUG: add support for string tables
            }
            else
            {
                _name = new String(name);
            }
            _virtualSize = getBigInt(buf);
            _virtualAddress = getBigInt(buf);
            _sizeOfRawData = getBigInt(buf);
            _ptrToRawData = getBigInt(buf);
            _ptrToRelocs = getBigInt(buf);
            _ptrToLineNos = getBigInt(buf);

            _numOfRelocs = buf.getShort();
            _numOfLineNos = buf.getShort();

            _characteristics = buf.getInt();
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

    PEHeader        _header;

    PESection[]     _sections;

    public PEHeader getHeader()
    {
        return _header;
    }

    public PESection[] getSections()
    {
        return _sections.clone();
    }

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

        _header = new PEHeader(_baseBuffer);

        initSections();
    }

    final void initSections()
    {
        try
        {
            _baseBuffer.position(_header.getEndPos());

            // BUGBUG: it might be prudent to limit the number of sections
            // to something sensible.
            // however, at ``short'' * SECTION_SIZE, it seems this number would
            // be low enough anyway.
            int numOfSections = _header.getNumOfSections();
            _sections = new PESection[numOfSections];

            for (int i = 0; i < numOfSections; ++i)
            {
                _sections[i] = new PESection(_baseBuffer);
            }
        }
        catch (Exception e)
        {
            return;
        }
    }
}
