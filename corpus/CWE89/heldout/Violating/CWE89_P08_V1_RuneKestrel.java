import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_RuneKestrel {

    public void runRuneKestrel() throws SQLException {
        String data;
        data = System.getenv("RUNE_KESTREL_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_RuneKestrelSink()).queryRuneKestrel(dataArray);
    }
}

class CWE89_P08_V1_RuneKestrelSink {
    public void queryRuneKestrel(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
