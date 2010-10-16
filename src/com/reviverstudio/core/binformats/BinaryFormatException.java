/**
 * Exception declarations
 *
 */

package com.reviverstudio.core.binformats;

/**
 *
 * @author assafs
 */
public class BinaryFormatException extends Exception {
    public enum Code
    {
        /** Unspecified failure */
        GeneralFailure,

        /** the MZ header is invalid */
        InvalidMZHeader,

        /** the PE header is invalid */
        InvalidPEHeader,

        /** Binary is of an unsupported architecture */
        BadArch,

        /** Invalid optional header */
        InvalidOptionalMagic,

        /** Sections are malformed within the PE */
        CorruptSections
    }


    Code _code;

    public Code getCode()
    {
        return _code;
    }

    public BinaryFormatException(Code c)
    {
        _code = c;
    }

    public BinaryFormatException()
    {
        _code = Code.GeneralFailure;
    }
}
