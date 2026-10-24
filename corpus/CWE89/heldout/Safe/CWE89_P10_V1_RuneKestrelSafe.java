import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_RuneKestrelSafe {

    public static String data;

    public void runRuneKestrel() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_RuneKestrelSafeSink()).queryRuneKestrel();
    }
}

class CWE89_P10_V1_RuneKestrelSafeSink {
    public void queryRuneKestrel() throws SQLException {
        String data = CWE89_P10_V1_RuneKestrelSafe.data;
        Connection runeKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeKestrel");
        Statement runeKestrelStatement = null;
        ResultSet runeKestrelRows = null;
        try {
            runeKestrelStatement = runeKestrelConnection.createStatement();
            runeKestrelRows = runeKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeKestrelRows.getRow());
        } finally {
            if (runeKestrelRows != null) {
                runeKestrelRows.close();
            }
            if (runeKestrelStatement != null) {
                runeKestrelStatement.close();
            }
            runeKestrelConnection.close();
        }
    }
}
