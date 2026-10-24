import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianLotusSafe {

    public void runObsidianLotus() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianLotusSafeSink()).queryObsidianLotus(dataArray);
    }
}

class CWE89_P08_V1_ObsidianLotusSafeSink {
    public void queryObsidianLotus(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection obsidianLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLotus");
        Statement obsidianLotusStatement = null;
        ResultSet obsidianLotusRows = null;
        try {
            obsidianLotusStatement = obsidianLotusConnection.createStatement();
            obsidianLotusRows = obsidianLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianLotusRows.getRow());
        } finally {
            if (obsidianLotusRows != null) {
                obsidianLotusRows.close();
            }
            if (obsidianLotusStatement != null) {
                obsidianLotusStatement.close();
            }
            obsidianLotusConnection.close();
        }
    }
}
