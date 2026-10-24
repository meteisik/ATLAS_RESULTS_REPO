import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VividAurora {

    public static String data;

    public void runVividAurora() throws XPathExpressionException {
        data = System.getenv("VIVID_AURORA_ADD");
        (new CWE643_P10_V1_VividAuroraSink()).sinkVividAurora();
    }
}

class CWE643_P10_V1_VividAuroraSink {

    public void sinkVividAurora() throws XPathExpressionException {
        String data = CWE643_P10_V1_VividAurora.data;
        String vividAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividAuroraTokens = data.split("||");
            if (vividAuroraTokens.length < 2) {
                return;
            }
            String vividAuroraUser = vividAuroraTokens[0];
            String vividAuroraPass = vividAuroraTokens[1];
            XPath vividAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource vividAuroraXml = new InputSource(vividAuroraXmlFile);
            String vividAuroraQuery = "//users/user[name/text()='" + vividAuroraUser
                    + "' and pass/text()='" + vividAuroraPass + "']" + "/secret/text()";
            String vividAuroraSecret = (String) vividAuroraXPath.evaluate(vividAuroraQuery, vividAuroraXml, XPathConstants.STRING);
            System.out.println(vividAuroraSecret);
        }
    }
}
