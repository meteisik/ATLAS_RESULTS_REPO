import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneRavenSafe {

    static class Container {
        public String containerOne;
    }

    public void runRuneRaven() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneRavenSafeSink()).queryRuneRaven(dataContainer);
    }
}

class CWE89_P09_V1_RuneRavenSafeSink {
    public void queryRuneRaven(CWE89_P09_V1_RuneRavenSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection runeRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeRaven");
        Statement runeRavenStatement = null;
        ResultSet runeRavenRows = null;
        try {
            runeRavenStatement = runeRavenConnection.createStatement();
            runeRavenRows = runeRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeRavenRows.getRow());
        } finally {
            if (runeRavenRows != null) {
                runeRavenRows.close();
            }
            if (runeRavenStatement != null) {
                runeRavenStatement.close();
            }
            runeRavenConnection.close();
        }
    }
}
