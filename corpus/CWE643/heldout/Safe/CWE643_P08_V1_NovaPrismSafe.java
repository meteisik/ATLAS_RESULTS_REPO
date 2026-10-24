import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_NovaPrismSafe {

    public void runNovaPrism() throws XPathExpressionException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_NovaPrismSafeSink()).sinkNovaPrism(dataArray);
    }
}

class CWE643_P08_V1_NovaPrismSafeSink {

    public void sinkNovaPrism(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String novaPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            novaPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            novaPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] novaPrismTokens = data.split("||");
            if (novaPrismTokens.length < 2) {
                return;
            }
            String novaPrismUser = novaPrismTokens[0];
            String novaPrismPass = novaPrismTokens[1];
            XPath novaPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource novaPrismXml = new InputSource(novaPrismXmlFile);
            String novaPrismQuery = "//users/user[name/text()='" + novaPrismUser
                    + "' and pass/text()='" + novaPrismPass + "']" + "/secret/text()";
            String novaPrismSecret = (String) novaPrismXPath.evaluate(novaPrismQuery, novaPrismXml, XPathConstants.STRING);
            System.out.println(novaPrismSecret);
        }
    }
}
