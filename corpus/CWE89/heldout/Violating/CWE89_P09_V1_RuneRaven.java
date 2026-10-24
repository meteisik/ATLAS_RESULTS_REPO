import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneRaven {

    static class Container {
        public String containerOne;
    }

    public void runRuneRaven() throws SQLException {
        String data;
        data = System.getenv("RUNE_RAVEN_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneRavenSink()).queryRuneRaven(dataContainer);
    }
}

class CWE89_P09_V1_RuneRavenSink {
    public void queryRuneRaven(CWE89_P09_V1_RuneRaven.Container dataContainer) throws SQLException {
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
