import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_VividSignalSafe {

    public static String data;

    public void runVividSignal() throws XPathExpressionException {
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_VividSignalSafeSink()).sinkVividSignal();
    }
}

class CWE643_P10_V2_VividSignalSafeSink {

    public void sinkVividSignal() throws XPathExpressionException {
        String data = CWE643_P10_V2_VividSignalSafe.data;
        String vividSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividSignalTokens = data.split("||");
            if (vividSignalTokens.length < 2) {
                return;
            }
            String vividSignalUser = vividSignalTokens[0];
            String vividSignalPass = vividSignalTokens[1];
            XPath vividSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource vividSignalXml = new InputSource(vividSignalXmlFile);
            String vividSignalQuery = "//users/user[name/text()='" + vividSignalUser
                    + "' and pass/text()='" + vividSignalPass + "']" + "/secret/text()";
            String vividSignalSecret = (String) vividSignalXPath.evaluate(vividSignalQuery, vividSignalXml, XPathConstants.STRING);
            System.out.println(vividSignalSecret);
        }
    }
}
