import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_NovaSignal {

    private String sourceNovaSignal() {
        String data;
        if (true) {
            data = System.getenv("NOVA_SIGNAL_ADD");
        } else {
            data = null;
        }
        return data;
    }

    public void runNovaSignal() throws XPathExpressionException {
        String data = sourceNovaSignal();
        String novaSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            novaSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            novaSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] novaSignalTokens = data.split("||");
            if (novaSignalTokens.length < 2) {
                return;
            }
            String novaSignalUser = novaSignalTokens[0];
            String novaSignalPass = novaSignalTokens[1];
            XPath novaSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource novaSignalXml = new InputSource(novaSignalXmlFile);
            String novaSignalQuery = "//users/user[name/text()='" + novaSignalUser
                    + "' and pass/text()='" + novaSignalPass + "']" + "/secret/text()";
            String novaSignalSecret = (String) novaSignalXPath.evaluate(novaSignalQuery, novaSignalXml, XPathConstants.STRING);
            System.out.println(novaSignalSecret);
        }
    }
}
