import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_VividSignal {

    public void runVividSignal() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("VIVID_SIGNAL_ADD");
            break;
        default:
            data = null;
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_VividSignalSink()).sinkVividSignal(dataArray);
    }
}

class CWE643_P08_V2_VividSignalSink {

    public void sinkVividSignal(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
