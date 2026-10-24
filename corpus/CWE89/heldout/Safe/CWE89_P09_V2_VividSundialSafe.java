import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VividSundialSafe {

    static class Container {
        public String containerOne;
    }

    public void runVividSundial() throws SQLException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VividSundialSafeSink()).queryVividSundial(dataContainer);
    }
}

class CWE89_P09_V2_VividSundialSafeSink {
    public void queryVividSundial(CWE89_P09_V2_VividSundialSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        Statement vividSundialStatement = null;
        ResultSet vividSundialRows = null;
        try {
            vividSundialStatement = vividSundialConnection.createStatement();
            vividSundialRows = vividSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividSundialRows.getRow());
        } finally {
            if (vividSundialRows != null) {
                vividSundialRows.close();
            }
            if (vividSundialStatement != null) {
                vividSundialStatement.close();
            }
            vividSundialConnection.close();
        }
    }
}
