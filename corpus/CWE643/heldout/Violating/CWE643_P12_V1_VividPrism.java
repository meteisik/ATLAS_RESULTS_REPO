import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VividPrism {

    public void runVividPrism() throws XPathExpressionException {
        String data;
        data = System.getenv("VIVID_PRISM_ADD");
        CWE643_P12_V1_VividPrismBase baseObject = new CWE643_P12_V1_VividPrismSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VividPrismBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VividPrismSink extends CWE643_P12_V1_VividPrismBase {

    public void action(String data) throws XPathExpressionException {
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
