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

                System.out.println("-- " + s);
                System.out.println("Machine: " + pe.getHeader().getMachine().toString());
                System.out.println("NumberOfSections: " + Integer.toString(pe.getHeader().getNumOfSections()));
                System.out.println("Opt Header Size: " + Integer.toString(pe.getHeader().getOptHeaderSize(), 0x10));
                System.out.println("TimeStamp: " + pe.getHeader().getTimeStamp().toString());
                System.out.println("Code base: " + pe.getHeader().getCodeBase().toString(0x10));
                System.out.println("Data base: " + pe.getHeader().getDataBase().toString(0x10));
                System.out.println("ImageBase: " + pe.getHeader().getImageBase().toString(0x10));
                System.out.println("Entry point: " + pe.getHeader().getEntryPoint().toString(0x10));
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

    @Test
    public void testLoadSane()
    {
        testLoadFile("test_bin/SimTower.exe");
    }

    @Test
    public void testLoadManySections()
    {
        // BUGBUG: not implemented yet
    }

    public void testSections(String s)
    {
        try
            {
                PortableExecutable pe = new PortableExecutable(s);

                PortableExecutable.PESection[] sections = pe.getSections();
                for (int i = 0; i < sections.length; ++i)
                {
                    System.out.println(s + "_" + Integer.toString(i) + ": " + sections[i].getName());
                }
            }
            catch (BinaryFormatException e)
            {
                fail(e.getCode().toString());
            }
            catch (Exception e)
            {
                fail(e.toString());
            }
    }

    @Test
    public void testSectionsSane()
    {
        testSections("test_bin/SimTower.exe");
    }

    @Test
    public void testSectionsSectionless()
    {
        testSections("test_bin/sectionless.exe");
    }

    @Test
    public void testSectionsTiny()
    {
        testSections("test_bin/tiny.exe");
    }

    @Test
    public void testSectionsTinyNG()
    {
        testSections("test_bin/tinypeng.exe");
    }
}