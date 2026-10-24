import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_SaffronSignalSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runSaffronSignal() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_SaffronSignalSafeSink()).sinkSaffronSignal(dataArray);
    }
}

class CWE643_P08_V2_SaffronSignalSafeSink {

    public void sinkSaffronSignal(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String saffronSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronSignalTokens = data.split("||");
            if (saffronSignalTokens.length < 2) {
                return;
            }
            String saffronSignalUser = saffronSignalTokens[0];
            String saffronSignalPass = saffronSignalTokens[1];
            XPath saffronSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronSignalXml = new InputSource(saffronSignalXmlFile);
            String saffronSignalQuery = "//users/user[name/text()='" + saffronSignalUser
                    + "' and pass/text()='" + saffronSignalPass + "']" + "/secret/text()";
            String saffronSignalSecret = (String) saffronSignalXPath.evaluate(saffronSignalQuery, saffronSignalXml, XPathConstants.STRING);
            System.out.println(saffronSignalSecret);
        }
    }
}
