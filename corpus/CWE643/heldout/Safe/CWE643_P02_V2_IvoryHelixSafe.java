import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_IvoryHelixSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runIvoryHelix() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String ivoryHelixXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                ivoryHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                ivoryHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] ivoryHelixTokens = data.split("||");
                if (ivoryHelixTokens.length < 2) {
                    return;
                }
                String ivoryHelixUser = ivoryHelixTokens[0];
                String ivoryHelixPass = ivoryHelixTokens[1];
                XPath ivoryHelixXPath = XPathFactory.newInstance().newXPath();
                InputSource ivoryHelixXml = new InputSource(ivoryHelixXmlFile);
                String ivoryHelixQuery = "//users/user[name/text()='" + ivoryHelixUser
                        + "' and pass/text()='" + ivoryHelixPass + "']" + "/secret/text()";
                String ivoryHelixSecret = (String) ivoryHelixXPath.evaluate(ivoryHelixQuery, ivoryHelixXml, XPathConstants.STRING);
                System.out.println(ivoryHelixSecret);
            }
        }
    }
}
