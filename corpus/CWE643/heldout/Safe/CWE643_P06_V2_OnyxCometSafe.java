import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_OnyxCometSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runOnyxComet() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P06_V2_OnyxCometSafeSink()).sinkOnyxComet(data);
    }
}

class CWE643_P06_V2_OnyxCometSafeSink {

    public void sinkOnyxComet(String data) throws XPathExpressionException {
        String onyxCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxCometTokens = data.split("||");
            if (onyxCometTokens.length < 2) {
                return;
            }
            String onyxCometUser = onyxCometTokens[0];
            String onyxCometPass = onyxCometTokens[1];
            XPath onyxCometXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxCometXml = new InputSource(onyxCometXmlFile);
            String onyxCometQuery = "//users/user[name/text()='" + onyxCometUser
                    + "' and pass/text()='" + onyxCometPass + "']" + "/secret/text()";
            String onyxCometSecret = (String) onyxCometXPath.evaluate(onyxCometQuery, onyxCometXml, XPathConstants.STRING);
            System.out.println(onyxCometSecret);
        }
    }
}
