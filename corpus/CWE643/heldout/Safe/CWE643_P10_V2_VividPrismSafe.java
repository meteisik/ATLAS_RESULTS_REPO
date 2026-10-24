import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_VividPrismSafe {

    public static String data;

    public void runVividPrism() throws XPathExpressionException {
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_VividPrismSafeSink()).sinkVividPrism();
    }
}

class CWE643_P10_V2_VividPrismSafeSink {

    public void sinkVividPrism() throws XPathExpressionException {
        String data = CWE643_P10_V2_VividPrismSafe.data;
        String vividPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividPrismTokens = data.split("||");
            if (vividPrismTokens.length < 2) {
                return;
            }
            String vividPrismUser = vividPrismTokens[0];
            String vividPrismPass = vividPrismTokens[1];
            XPath vividPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource vividPrismXml = new InputSource(vividPrismXmlFile);
            String vividPrismQuery = "//users/user[name/text()='" + vividPrismUser
                    + "' and pass/text()='" + vividPrismPass + "']" + "/secret/text()";
            String vividPrismSecret = (String) vividPrismXPath.evaluate(vividPrismQuery, vividPrismXml, XPathConstants.STRING);
            System.out.println(vividPrismSecret);
        }
    }
}
