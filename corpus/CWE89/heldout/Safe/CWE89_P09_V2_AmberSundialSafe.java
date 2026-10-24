import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberSundialSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String containerOne;
    }

    public void runAmberSundial() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberSundialSafeSink()).queryAmberSundial(dataContainer);
    }
}

class CWE89_P09_V2_AmberSundialSafeSink {
    public void queryAmberSundial(CWE89_P09_V2_AmberSundialSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection amberSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberSundial");
        Statement amberSundialStatement = null;
        ResultSet amberSundialRows = null;
        try {
            amberSundialStatement = amberSundialConnection.createStatement();
            amberSundialRows = amberSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberSundialRows.getRow());
        } finally {
            if (amberSundialRows != null) {
                amberSundialRows.close();
            }
            if (amberSundialStatement != null) {
                amberSundialStatement.close();
            }
            amberSundialConnection.close();
        }
    }
}
