import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_JadeAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runJadeAurora() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Connection jadeAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeAurora");
        Statement jadeAuroraStatement = null;
        ResultSet jadeAuroraRows = null;
        try {
            jadeAuroraStatement = jadeAuroraConnection.createStatement();
            jadeAuroraRows = jadeAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeAuroraRows.getRow());
        } finally {
            if (jadeAuroraRows != null) {
                jadeAuroraRows.close();
            }
            if (jadeAuroraStatement != null) {
                jadeAuroraStatement.close();
            }
            jadeAuroraConnection.close();
        }
    }
}
