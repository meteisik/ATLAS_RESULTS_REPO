import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_MosaicKestrel {

    private String mosaicKestrelData;

    private void sinkMosaicKestrel() throws XPathExpressionException {
        String data = mosaicKestrelData;
        String mosaicKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            mosaicKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            mosaicKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] mosaicKestrelTokens = data.split("||");
            if (mosaicKestrelTokens.length < 2) {
                return;
            }
            String mosaicKestrelUser = mosaicKestrelTokens[0];
            String mosaicKestrelPass = mosaicKestrelTokens[1];
            XPath mosaicKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource mosaicKestrelXml = new InputSource(mosaicKestrelXmlFile);
            String mosaicKestrelQuery = "//users/user[name/text()='" + mosaicKestrelUser
                    + "' and pass/text()='" + mosaicKestrelPass + "']" + "/secret/text()";
            String mosaicKestrelSecret = (String) mosaicKestrelXPath.evaluate(mosaicKestrelQuery, mosaicKestrelXml, XPathConstants.STRING);
            System.out.println(mosaicKestrelSecret);
        }
    }

    public void runMosaicKestrel() throws XPathExpressionException {
        String data;
        data = System.getenv("MOSAIC_KESTREL_ADD");
        mosaicKestrelData = data;
        sinkMosaicKestrel();
    }
}
