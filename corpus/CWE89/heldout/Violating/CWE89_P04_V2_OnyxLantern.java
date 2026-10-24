import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_OnyxLantern {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String loadOnyxLantern() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_LANTERN_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runOnyxLantern() throws SQLException {
        String data = loadOnyxLantern();
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        Statement onyxLanternStatement = null;
        ResultSet onyxLanternRows = null;
        try {
            onyxLanternStatement = onyxLanternConnection.createStatement();
            onyxLanternRows = onyxLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxLanternRows.getRow());
        } finally {
            if (onyxLanternRows != null) {
                onyxLanternRows.close();
            }
            if (onyxLanternStatement != null) {
                onyxLanternStatement.close();
            }
            onyxLanternConnection.close();
        }
    }
}
