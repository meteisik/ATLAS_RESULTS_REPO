import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberMantis {

    static class Container {
        public String containerOne;
    }

    public void runAmberMantis() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("AMBER_MANTIS_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberMantisSink()).queryAmberMantis(dataContainer);
    }
}

class CWE89_P09_V2_AmberMantisSink {
    public void queryAmberMantis(CWE89_P09_V2_AmberMantis.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        Statement amberMantisStatement = null;
        ResultSet amberMantisRows = null;
        try {
            amberMantisStatement = amberMantisConnection.createStatement();
            amberMantisRows = amberMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberMantisRows.getRow());
        } finally {
            if (amberMantisRows != null) {
                amberMantisRows.close();
            }
            if (amberMantisStatement != null) {
                amberMantisStatement.close();
            }
            amberMantisConnection.close();
        }
    }
}
