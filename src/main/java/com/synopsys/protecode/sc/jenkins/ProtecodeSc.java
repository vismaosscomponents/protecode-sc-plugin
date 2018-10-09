/*******************************************************************************
 * Copyright (c) 2016 Synopsys, Inc
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Synopsys, Inc - initial implementation and documentation
 *******************************************************************************/

package com.synopsys.protecode.sc.jenkins;

import com.fasterxml.jackson.annotation.JsonProperty;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class ProtecodeSc {

    private String artifactName;

    private Results results;

    private Meta meta;

    public void setArtifactName(String artifactName) {
        this.artifactName = artifactName;
    }

    public String getArtifactName() {
        return artifactName;
    }

    public Meta getMeta() {
        return meta;
    }

    public Results getResults() {
        return results;
    }

    public static enum Status {
        B("Busy"), R("Ready"), F("Fail");

        private String value;

        private Status(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    public static class Meta {
        private Integer code;

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public Integer getCode() {
            return code;
        }
    }

    public static class CustomData {
    }

    public static class Results {

        private Integer id;

        private String sha1sum;

        private Summary summary;

        private List<Component> components;

        private Status status;

        private String report_url;

        private Details details;

        private String filename;

        private Integer product_id;

        private String last_updated;

        @JsonProperty("rescan-possible")
        private boolean rescanPossible;

        private boolean stale;

        private Map<String, String> custom_data;

        public Summary getSummary() {
            return summary;
        }

        public List<Component> getComponents() {
            return components;
        }

        public Integer getId() {
            return id;
        }

        public Status getStatus() {
            return status;
        }

        public String getSha1sum() {
            return sha1sum;
        }

        public String getReport_url() {
            return report_url;
        }

        public Details getDetails() {
            return details;
        }

        public String getFilename() {
            return filename;
        }

        public Integer getProduct_id() {
            return product_id;
        }

        public String getLast_updated() {
            return last_updated;
        }

        public boolean isRescanPossible() {
            return rescanPossible;
        }

        public boolean isStale() {
            return stale;
        }

        public Map<String, String> getCustom_data() {
            return custom_data;
        }
    }

    public static class Summary {
        private Verdict verdict;
        @JsonProperty("vuln-count")
        private VulnCount vulnCount;

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public Verdict getVerdict() {
            return verdict;
        }

        public VulnCount getVulnCount() {
            return vulnCount;
        }

    }

    public static class Verdict {
        private String detailed;
        @JsonProperty("short")
        private String shortDesc;

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public String getDetailed() {
            return detailed;
        }

        public String getShortDesc() {
            return shortDesc;
        }
    }

    public static class VulnCount {
        private Long total;
        private Long exact;
        private Long historical;

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public Long getTotal() {
            return total;
        }

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public Long getExact() {
            return exact;
        }

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public Long getHistorical() {
            return historical;
        }
    }

    public static class ExtendedObject {
        private Double confidence;
        private String sha1;
        private String name;
        private long timestamp;
        @JsonProperty("matching-method")
        private String matchingMethod;
        private List<String> fullpath;
        private String type;
        @JsonProperty("source-match")
        private String sourceMatch;
        @JsonProperty("binary-type")
        private String binaryType;

        public Double getConfidence() {
            return confidence;
        }

        public String getSha1() {
            return sha1;
        }

        public String getName() {
            return name;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public String getMatchingMethod() {
            return matchingMethod;
        }

        public Collection<String> getFullpath() {
            return fullpath;
        }

        public String getType() {
            return type;
        }

        public String getSourceMatch() {
            return sourceMatch;
        }

        public String getBinaryType() {
            return binaryType;
        }
    }

    public static class Component {
        @JsonProperty("extended-objects")
        private List<ExtendedObject> extendedObjects;
        private License license;
        private String lib;
        private List<String> tags;
        private String url;
        private List<String> cpe;
        private List<Vuln> vulns;
        private Boolean latest_cmp;
        private String latest_version;
        private String version;
        private CoverityScan coverity_scan;
        @JsonProperty("latest-version")
        private String latestVersion;
        private List<String> objects;
        private String codetype;
        private String short_version;
        private String homepage;
        @JsonProperty("vuln-count")
        private VulnCount vulnCount;
        @JsonProperty("upstream-source")
        private String upstreamSource;

        public List<ExtendedObject> getExtendedObjects() {
            return extendedObjects;
        }

        public License getLicense() {
            return license;
        }

        public String getLib() {
            return lib;
        }

        public List<String> getTags() {
            return tags;
        }

        public String getUrl() {
            return url;
        }

        public List<String> getCpe() {
            return cpe;
        }

        public List<Vuln> getVulns() {
            return vulns;
        }

        public Boolean getLatest_cmp() {
            return latest_cmp;
        }

        public String getLatest_version() {
            return latest_version;
        }

        public String getVersion() {
            return version;
        }

        public CoverityScan getCoverity_scan() {
            return coverity_scan;
        }

        public String getLatestVersion() {
            return latestVersion;
        }

        public List<String> getObjects() {
            return objects;
        }

        public String getCodetype() {
            return codetype;
        }

        public String getShort_version() {
            return short_version;
        }

        public String getHomepage() {
            return homepage;
        }

        public VulnCount getVulnCount() {
            return vulnCount;
        }

        public String getUpstreamSource() {
            return upstreamSource;
        }
    }

    public static class Details2 {
        private Object loc;
        private Object defect_density;
        private Object build_date;
        private String project_url;
        private Object version;
        private List<Object> cwe;

        public Object getLoc() {
            return loc;
        }

        public Object getDefect_density() {
            return defect_density;
        }

        public Object getBuild_date() {
            return build_date;
        }

        public String getProject_url() {
            return project_url;
        }

        public Object getVersion() {
            return version;
        }

        public List<Object> getCwe() {
            return cwe;
        }
    }

    public static class CoverityScan {
        @JsonProperty("mapped-name")
        private String mappedname;
        private String name;
        private String language;
        private long id;
        private String homepage_url;
        private Details2 details;
        private String repo_url;
        private String slug;

        public String getMappedname() {
            return mappedname;
        }

        public String getName() {
            return name;
        }

        public String getLanguage() {
            return language;
        }

        public long getId() {
            return id;
        }

        public String getHomepage_url() {
            return homepage_url;
        }

        public Details2 getDetails() {
            return details;
        }

        public String getRepo_url() {
            return repo_url;
        }

        public String getSlug() {
            return slug;
        }
    }

    public static class Vuln {
        private boolean exact;
        private VulnDetails vuln;
        @JsonProperty("timestamp-objects")
        private List<String> timestampObjects;

        public boolean isExact() {
            return exact;
        }

        public List<String> getTimestampObjects() {
            return timestampObjects;
        }

        public VulnDetails getVuln() {
            return vuln;
        }

        public void setVuln(VulnDetails vuln) {
            this.vuln = vuln;
        }
    }

    public static class VulnDetails {
        public String cve;
        public Double cvss;

        public String cvss_created;
        public String cvss_access_complexity;
        public String cvss2_vector;
        public String cvss_source;
        public String cwe;
        @JsonProperty("cvss_created-epoch")
        public String cvss_createdepoch;
        @JsonProperty("modified-epoch")
        public String modifiedepoch;
        public String modified;
        public String cvss_availability_impact;
        public String summary;

        public String cvss_authentication;
        public String published;

        public String cvss_confidentiality_impact;
        public String cvss_access_vector;
        @JsonProperty("published-epoch")
        public String publishedepoch;
        public String cvss_integrity_impact;


        public String cvss3_score;

        public String getCvss3_score() {
            return cvss3_score;
        }

        public String getCve() {
            return cve;
        }

        public Double getCvss() {
            return cvss;
        }

        public String getCvss_created() {
            return cvss_created;
        }

        public String getCvss_access_complexity() {
            return cvss_access_complexity;
        }

        public String getCvss2_vector() {
            return cvss2_vector;
        }

        public String getCvss_source() {
            return cvss_source;
        }

        public String getCwe() {
            return cwe;
        }

        public String getCvss_createdepoch() {
            return cvss_createdepoch;
        }

        public String getModifiedepoch() {
            return modifiedepoch;
        }

        public String getModified() {
            return modified;
        }

        public String getCvss_availability_impact() {
            return cvss_availability_impact;
        }

        public String getSummary() {
            return summary;
        }

        public String getCvss_authentication() {
            return cvss_authentication;
        }

        public String getPublished() {
            return published;
        }

        public String getCvss_confidentiality_impact() {
            return cvss_confidentiality_impact;
        }

        public String getCvss_access_vector() {
            return cvss_access_vector;
        }

        public String getPublishedepoch() {
            return publishedepoch;
        }

        public String getCvss_integrity_impact() {
            return cvss_integrity_impact;
        }
    }

    public static class License {
        private String url;
        private String type;
        private String name;

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public String getUrl() {
            return url;
        }

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public String getType() {
            return type;
        }

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public String getName() {
            return name;
        }

    }

    public static class Details {
        private Map<String, Integer> filetypes;
        private Map<String, List<String>> flagged;

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public Map<String, Integer> getFiletypes() {
            return filetypes;
        }

        public Map<String, List<String>> getFlagged() {
            return flagged;
        }

    }

    public static class Filetype {
        Map<String, Integer> val;

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public Map<String, Integer> getVal() {
            return val;
        }
    }

    public static class Flagged {
        Map<String, List<String>> val;

        @SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
        public Map<String, List<String>> getVal() {
            return val;
        }
    }

    public static class Metadata {
        /// <summary>
        /// e.g. Android, OS X
        /// </summary>
        /// <returns></returns>
        public String platform;
        public int depth;
        public String version;
        public Object vendor;
        /// <summary>
        /// application name
        /// </summary>
        /// <returns></returns>
        public String name;

        public String getPlatform() {
            return platform;
        }

        public int getDepth() {
            return depth;
        }

        public String getVersion() {
            return version;
        }

        public Object getVendor() {
            return vendor;
        }

        public String getName() {
            return name;
        }
    }
}
