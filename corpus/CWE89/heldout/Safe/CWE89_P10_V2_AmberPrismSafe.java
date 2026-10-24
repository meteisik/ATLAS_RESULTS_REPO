import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberPrismSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void runAmberPrism() throws SQLException {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AmberPrismSafeSink()).queryAmberPrism();
    }
}

class CWE89_P10_V2_AmberPrismSafeSink {
    public void queryAmberPrism() throws SQLException {
        String data = CWE89_P10_V2_AmberPrismSafe.data;
        Connection amberPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberPrism");
        Statement amberPrismStatement = null;
        ResultSet amberPrismRows = null;
        try {
            amberPrismStatement = amberPrismConnection.createStatement();
            amberPrismRows = amberPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberPrismRows.getRow());
        } finally {
            if (amberPrismRows != null) {
                amberPrismRows.close();
            }
            if (amberPrismStatement != null) {
                amberPrismStatement.close();
            }
            amberPrismConnection.close();
        }
    }
}
