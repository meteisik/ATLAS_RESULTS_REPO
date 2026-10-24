import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SaffronMantis {

    public void runSaffronMantis() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = (new CWE89_P07_V2_SaffronMantisSource()).loadSaffronMantis();
            break;
        default:
            data = null;
            break;
        }
        Connection saffronMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronMantis");
        Statement saffronMantisStatement = null;
        ResultSet saffronMantisRows = null;
        try {
            saffronMantisStatement = saffronMantisConnection.createStatement();
            saffronMantisRows = saffronMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronMantisRows.getRow());
        } finally {
            if (saffronMantisRows != null) {
                saffronMantisRows.close();
            }
            if (saffronMantisStatement != null) {
                saffronMantisStatement.close();
            }
            saffronMantisConnection.close();
        }
    }
}

class CWE89_P07_V2_SaffronMantisSource {
    public String loadSaffronMantis() {
        String data;
        data = System.getenv("SAFFRON_MANTIS_FILTER");
        return data;
    }
}
