import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AmberMantis {
    private static boolean privateTrue = true;

    public static String data;

    public void runAmberMantis() throws XPathExpressionException {
        if (privateTrue) {
            data = System.getenv("AMBER_MANTIS_ADD");
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AmberMantisSink()).sinkAmberMantis();
    }
}

class CWE643_P10_V2_AmberMantisSink {

    public void sinkAmberMantis() throws XPathExpressionException {
        String data = CWE643_P10_V2_AmberMantis.data;
        String amberMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberMantisTokens = data.split("||");
            if (amberMantisTokens.length < 2) {
                return;
            }
            String amberMantisUser = amberMantisTokens[0];
            String amberMantisPass = amberMantisTokens[1];
            XPath amberMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource amberMantisXml = new InputSource(amberMantisXmlFile);
            String amberMantisQuery = "//users/user[name/text()='" + amberMantisUser
                    + "' and pass/text()='" + amberMantisPass + "']" + "/secret/text()";
            String amberMantisSecret = (String) amberMantisXPath.evaluate(amberMantisQuery, amberMantisXml, XPathConstants.STRING);
            System.out.println(amberMantisSecret);
        }
    }
}
