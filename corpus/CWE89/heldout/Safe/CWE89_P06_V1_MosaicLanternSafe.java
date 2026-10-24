import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicLanternSafe {

    public void runMosaicLantern() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_MosaicLanternSafeSink()).queryMosaicLantern(data);
    }
}

class CWE89_P06_V1_MosaicLanternSafeSink {
    public void queryMosaicLantern(String data) throws SQLException {
        Connection mosaicLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLantern");
        Statement mosaicLanternStatement = null;
        ResultSet mosaicLanternRows = null;
        try {
            mosaicLanternStatement = mosaicLanternConnection.createStatement();
            mosaicLanternRows = mosaicLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicLanternRows.getRow());
        } finally {
            if (mosaicLanternRows != null) {
                mosaicLanternRows.close();
            }
            if (mosaicLanternStatement != null) {
                mosaicLanternStatement.close();
            }
            mosaicLanternConnection.close();
        }
    }
}
