import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetSignal {

    public static String data;

    public void runVelvetSignal() throws XPathExpressionException {
        data = System.getenv("VELVET_SIGNAL_ADD");
        (new CWE643_P10_V1_VelvetSignalSink()).sinkVelvetSignal();
    }
}

class CWE643_P10_V1_VelvetSignalSink {

    public void sinkVelvetSignal() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetSignal.data;
        String velvetSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetSignalTokens = data.split("||");
            if (velvetSignalTokens.length < 2) {
                return;
            }
            String velvetSignalUser = velvetSignalTokens[0];
            String velvetSignalPass = velvetSignalTokens[1];
            XPath velvetSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetSignalXml = new InputSource(velvetSignalXmlFile);
            String velvetSignalQuery = "//users/user[name/text()='" + velvetSignalUser
                    + "' and pass/text()='" + velvetSignalPass + "']" + "/secret/text()";
            String velvetSignalSecret = (String) velvetSignalXPath.evaluate(velvetSignalQuery, velvetSignalXml, XPathConstants.STRING);
            System.out.println(velvetSignalSecret);
        }
    }
}
