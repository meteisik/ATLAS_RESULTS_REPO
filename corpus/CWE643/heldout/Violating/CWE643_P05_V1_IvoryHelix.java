import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_IvoryHelix {

    private String ivoryHelixData;

    private void sinkIvoryHelix() throws XPathExpressionException {
        String data = ivoryHelixData;
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

    public void runIvoryHelix() throws XPathExpressionException {
        String data;
        data = System.getenv("IVORY_HELIX_ADD");
        ivoryHelixData = data;
        sinkIvoryHelix();
    }
}
