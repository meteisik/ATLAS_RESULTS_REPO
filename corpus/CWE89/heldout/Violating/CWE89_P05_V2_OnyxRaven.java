import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_OnyxRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String onyxRavenData;

    private void queryOnyxRaven() throws SQLException {
        String data = onyxRavenData;
        Connection onyxRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxRaven");
        Statement onyxRavenStatement = null;
        ResultSet onyxRavenRows = null;
        try {
            onyxRavenStatement = onyxRavenConnection.createStatement();
            onyxRavenRows = onyxRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxRavenRows.getRow());
        } finally {
            if (onyxRavenRows != null) {
                onyxRavenRows.close();
            }
            if (onyxRavenStatement != null) {
                onyxRavenStatement.close();
            }
            onyxRavenConnection.close();
        }
    }

    public void runOnyxRaven() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ONYX_RAVEN_FILTER");
        } else {
            data = null;
        }
        onyxRavenData = data;
        queryOnyxRaven();
    }
}
