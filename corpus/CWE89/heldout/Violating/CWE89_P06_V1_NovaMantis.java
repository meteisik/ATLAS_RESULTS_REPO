import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_NovaMantis {

    public void runNovaMantis() throws SQLException {
        String data;
        data = System.getenv("NOVA_MANTIS_FILTER");
        (new CWE89_P06_V1_NovaMantisSink()).queryNovaMantis(data);
    }
}

class CWE89_P06_V1_NovaMantisSink {
    public void queryNovaMantis(String data) throws SQLException {
        Connection novaMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaMantis");
        Statement novaMantisStatement = null;
        ResultSet novaMantisRows = null;
        try {
            novaMantisStatement = novaMantisConnection.createStatement();
            novaMantisRows = novaMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaMantisRows.getRow());
        } finally {
            if (novaMantisRows != null) {
                novaMantisRows.close();
            }
            if (novaMantisStatement != null) {
                novaMantisStatement.close();
            }
            novaMantisConnection.close();
        }
    }
}
