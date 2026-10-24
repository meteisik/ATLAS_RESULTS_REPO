import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianKestrel {

    public void runObsidianKestrel() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianKestrelSink()).queryObsidianKestrel(dataArray);
    }
}

class CWE89_P08_V1_ObsidianKestrelSink {
    public void queryObsidianKestrel(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection obsidianKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianKestrel");
        Statement obsidianKestrelStatement = null;
        ResultSet obsidianKestrelRows = null;
        try {
            obsidianKestrelStatement = obsidianKestrelConnection.createStatement();
            obsidianKestrelRows = obsidianKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianKestrelRows.getRow());
        } finally {
            if (obsidianKestrelRows != null) {
                obsidianKestrelRows.close();
            }
            if (obsidianKestrelStatement != null) {
                obsidianKestrelStatement.close();
            }
            obsidianKestrelConnection.close();
        }
    }
}
