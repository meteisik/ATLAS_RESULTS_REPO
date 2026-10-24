import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_IvoryKestrelSafe {

    private void queryIvoryKestrel(String data) throws SQLException {
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

    public void runIvoryKestrel() throws SQLException {
        String data;
        data = "foo";
        queryIvoryKestrel(data);
    }
}
