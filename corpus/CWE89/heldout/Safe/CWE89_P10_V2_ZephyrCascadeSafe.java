import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ZephyrCascadeSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void runZephyrCascade() throws SQLException {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ZephyrCascadeSafeSink()).queryZephyrCascade();
    }
}

class CWE89_P10_V2_ZephyrCascadeSafeSink {
    public void queryZephyrCascade() throws SQLException {
        String data = CWE89_P10_V2_ZephyrCascadeSafe.data;
        Connection zephyrCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCascade");
        Statement zephyrCascadeStatement = null;
        ResultSet zephyrCascadeRows = null;
        try {
            zephyrCascadeStatement = zephyrCascadeConnection.createStatement();
            zephyrCascadeRows = zephyrCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrCascadeRows.getRow());
        } finally {
            if (zephyrCascadeRows != null) {
                zephyrCascadeRows.close();
            }
            if (zephyrCascadeStatement != null) {
                zephyrCascadeStatement.close();
            }
            zephyrCascadeConnection.close();
        }
    }
}
