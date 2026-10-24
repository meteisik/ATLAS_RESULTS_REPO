import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianHelixSafe {

    public void runObsidianHelix() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianHelixSafeSink()).queryObsidianHelix(dataArray);
    }
}

class CWE89_P08_V1_ObsidianHelixSafeSink {
    public void queryObsidianHelix(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection obsidianHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHelix");
        Statement obsidianHelixStatement = null;
        ResultSet obsidianHelixRows = null;
        try {
            obsidianHelixStatement = obsidianHelixConnection.createStatement();
            obsidianHelixRows = obsidianHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianHelixRows.getRow());
        } finally {
            if (obsidianHelixRows != null) {
                obsidianHelixRows.close();
            }
            if (obsidianHelixStatement != null) {
                obsidianHelixStatement.close();
            }
            obsidianHelixConnection.close();
        }
    }
}
