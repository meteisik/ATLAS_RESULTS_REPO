import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberCascadeSafe {

    static class Container {
        public String containerOne;
    }

    public void runAmberCascade() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberCascadeSafeSink()).queryAmberCascade(dataContainer);
    }
}

class CWE89_P09_V2_AmberCascadeSafeSink {
    public void queryAmberCascade(CWE89_P09_V2_AmberCascadeSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection amberCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCascade");
        Statement amberCascadeStatement = null;
        ResultSet amberCascadeRows = null;
        try {
            amberCascadeStatement = amberCascadeConnection.createStatement();
            amberCascadeRows = amberCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberCascadeRows.getRow());
        } finally {
            if (amberCascadeRows != null) {
                amberCascadeRows.close();
            }
            if (amberCascadeStatement != null) {
                amberCascadeStatement.close();
            }
            amberCascadeConnection.close();
        }
    }
}
