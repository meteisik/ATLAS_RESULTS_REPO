import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_OnyxKestrelSafe {
    private static int privateFive = 5;

    public void runOnyxKestrel() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_OnyxKestrelSafeSink()).queryOnyxKestrel(data);
    }
}

class CWE89_P06_V2_OnyxKestrelSafeSink {
    public void queryOnyxKestrel(String data) throws SQLException {
        Connection onyxKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxKestrel");
        Statement onyxKestrelStatement = null;
        ResultSet onyxKestrelRows = null;
        try {
            onyxKestrelStatement = onyxKestrelConnection.createStatement();
            onyxKestrelRows = onyxKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxKestrelRows.getRow());
        } finally {
            if (onyxKestrelRows != null) {
                onyxKestrelRows.close();
            }
            if (onyxKestrelStatement != null) {
                onyxKestrelStatement.close();
            }
            onyxKestrelConnection.close();
        }
    }
}
