import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_IvoryKestrel {

    private void sinkIvoryKestrel(String data) throws XPathExpressionException {
        String ivoryKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryKestrelTokens = data.split("||");
            if (ivoryKestrelTokens.length < 2) {
                return;
            }
            String ivoryKestrelUser = ivoryKestrelTokens[0];
            String ivoryKestrelPass = ivoryKestrelTokens[1];
            XPath ivoryKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryKestrelXml = new InputSource(ivoryKestrelXmlFile);
            String ivoryKestrelQuery = "//users/user[name/text()='" + ivoryKestrelUser
                    + "' and pass/text()='" + ivoryKestrelPass + "']" + "/secret/text()";
            String ivoryKestrelSecret = (String) ivoryKestrelXPath.evaluate(ivoryKestrelQuery, ivoryKestrelXml, XPathConstants.STRING);
            System.out.println(ivoryKestrelSecret);
        }
    }

    public void runIvoryKestrel() throws XPathExpressionException {
        String data;
        data = System.getenv("IVORY_KESTREL_ADD");
        sinkIvoryKestrel(data);
    }
}
