import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberPrismSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void runAmberPrism() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberPrismSafeSink()).queryAmberPrism(dataContainer);
    }
}

class CWE89_P09_V2_AmberPrismSafeSink {
    public void queryAmberPrism(CWE89_P09_V2_AmberPrismSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection amberPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberPrism");
        Statement amberPrismStatement = null;
        ResultSet amberPrismRows = null;
        try {
            amberPrismStatement = amberPrismConnection.createStatement();
            amberPrismRows = amberPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberPrismRows.getRow());
        } finally {
            if (amberPrismRows != null) {
                amberPrismRows.close();
            }
            if (amberPrismStatement != null) {
                amberPrismStatement.close();
            }
            amberPrismConnection.close();
        }
    }
}
