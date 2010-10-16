package com.reviverstudio.core.binformats;

import java.io.*;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author assafs
 */
public class PortableExecutableTest {

    public PortableExecutableTest() {
        
    }

    void testLoadFile(String s)
    {
        try
            {
                PortableExecutable pe = new PortableExecutable(s);
            }
            catch (IOException e)
            {
                fail(e.toString());
            }
            catch (BinaryFormatException e)
            {
                fail(e.getCode().toString());
            }
    }

    @Test
    public void testLoadSectionless() {
        testLoadFile("test_bin/sectionless.exe");
    }

    @Test
    public void testLoadTiny()
    {
        testLoadFile("test_bin/tiny.exe");
    }

    @Test
    public void testLoadTinyNG()
    {
        testLoadFile("test_bin/tinypeng.exe");
    }

}