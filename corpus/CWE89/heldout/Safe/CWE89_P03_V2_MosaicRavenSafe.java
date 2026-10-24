import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_MosaicRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void queryMosaicRaven(String data) throws SQLException {
        Connection mosaicRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicRaven");
        Statement mosaicRavenStatement = null;
        ResultSet mosaicRavenRows = null;
        try {
            mosaicRavenStatement = mosaicRavenConnection.createStatement();
            mosaicRavenRows = mosaicRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicRavenRows.getRow());
        } finally {
            if (mosaicRavenRows != null) {
                mosaicRavenRows.close();
            }
            if (mosaicRavenStatement != null) {
                mosaicRavenStatement.close();
            }
            mosaicRavenConnection.close();
        }
    }

    public void runMosaicRaven() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        queryMosaicRaven(data);
    }
}
