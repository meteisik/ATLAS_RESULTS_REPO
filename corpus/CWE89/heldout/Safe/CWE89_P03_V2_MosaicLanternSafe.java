import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_MosaicLanternSafe {
    private static boolean privateTrue = true;

    private void queryMosaicLantern(String data) throws SQLException {
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

    public void runMosaicLantern() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        queryMosaicLantern(data);
    }
}
