package com.synopsys.protecode.sc.jenkins;

import java.io.File;
import java.io.FileFilter;
import java.io.Serializable;

@SuppressWarnings("serial")
class ScanFileFilter implements FileFilter, Serializable {

    @Override
    public boolean accept(File pathname) {
        return pathname.isFile();

    }
}
