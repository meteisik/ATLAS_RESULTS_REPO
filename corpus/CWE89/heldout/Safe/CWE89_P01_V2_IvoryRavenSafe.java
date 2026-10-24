import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_IvoryRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryRaven() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Connection ivoryRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryRaven");
        Statement ivoryRavenStatement = null;
        ResultSet ivoryRavenRows = null;
        try {
            ivoryRavenStatement = ivoryRavenConnection.createStatement();
            ivoryRavenRows = ivoryRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryRavenRows.getRow());
        } finally {
            if (ivoryRavenRows != null) {
                ivoryRavenRows.close();
            }
            if (ivoryRavenStatement != null) {
                ivoryRavenStatement.close();
            }
            ivoryRavenConnection.close();
        }
    }
}
