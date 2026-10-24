import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_IvoryKestrelSafe {
    private static int privateFive = 5;

    public void runIvoryKestrel() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Connection ivoryKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryKestrel");
        Statement ivoryKestrelStatement = null;
        ResultSet ivoryKestrelRows = null;
        try {
            ivoryKestrelStatement = ivoryKestrelConnection.createStatement();
            ivoryKestrelRows = ivoryKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryKestrelRows.getRow());
        } finally {
            if (ivoryKestrelRows != null) {
                ivoryKestrelRows.close();
            }
            if (ivoryKestrelStatement != null) {
                ivoryKestrelStatement.close();
            }
            ivoryKestrelConnection.close();
        }
    }
}
