import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V1_JadePrismSafe {

    private String sourceJadePrism() {
        String data;
        data = "foo";
        return data;
    }

    public void runJadePrism() throws XPathExpressionException {
        String data = sourceJadePrism();
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
}
