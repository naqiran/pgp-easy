package com.naqiran.pgp.easy;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class IOUtils {

    public static final InputStream getInputStream(final String fileName) throws IOException {
        return new BufferedInputStream(new FileInputStream(fileName));
    }

    public static final OutputStream getOutputStream(final String fileName) throws IOException {
        return new BufferedOutputStream(new FileOutputStream(fileName));
    }
}
