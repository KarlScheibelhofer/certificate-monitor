package dev.scheibelhofer.certificate.monitor;

import java.io.IOException;
import java.util.Collection;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

public class CSVSupport {

    public static String toCSV(Collection<Certificate> certList) {
        StringBuilder sb = new StringBuilder();
        try (CSVPrinter csv = CSVFormat.EXCEL.print(sb)) {
            csv.printRecord("validNotAfter", "dnsNames", "subjectDN", "issuerDN", "serial", "id", "validNotBefore", "pemEncoded");
            for (Certificate cert : certList) {
                csv.printRecord(
                    cert.validNotAfter, String.join(",", cert.dnsNames), cert.subjectDN, 
                    cert.issuerDN, cert.serial, cert.id, cert.validNotBefore,
                    cert.pemEncoded.replace("\r\n", "\\r\\n"));
            }
        } catch (IOException e) {
            throw new RuntimeException("failed creating CSV", e);
        }        
        return sb.toString();
    }

}
