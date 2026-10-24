import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_JadePrism {
    private static boolean privateReturnsTrue() { return true; }

    private void sinkJadePrism(String data) throws XPathExpressionException {
        String jadePrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadePrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadePrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadePrismTokens = data.split("||");
            if (jadePrismTokens.length < 2) {
                return;
            }
            String jadePrismUser = jadePrismTokens[0];
            String jadePrismPass = jadePrismTokens[1];
            XPath jadePrismXPath = XPathFactory.newInstance().newXPath();
            InputSource jadePrismXml = new InputSource(jadePrismXmlFile);
            String jadePrismQuery = "//users/user[name/text()='" + jadePrismUser
                    + "' and pass/text()='" + jadePrismPass + "']" + "/secret/text()";
            String jadePrismSecret = (String) jadePrismXPath.evaluate(jadePrismQuery, jadePrismXml, XPathConstants.STRING);
            System.out.println(jadePrismSecret);
        }
    }

    public void runJadePrism() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("JADE_PRISM_ADD");
        } else {
            data = null;
        }
        sinkJadePrism(data);
    }
}
