import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneKestrelSafe {

    static class Container {
        public String containerOne;
    }

    public void runRuneKestrel() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneKestrelSafeSink()).queryRuneKestrel(dataContainer);
    }
}

class CWE89_P09_V1_RuneKestrelSafeSink {
    public void queryRuneKestrel(CWE89_P09_V1_RuneKestrelSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
