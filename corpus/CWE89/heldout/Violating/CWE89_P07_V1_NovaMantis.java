import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_NovaMantis {

    public void runNovaMantis() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_NovaMantisSource()).loadNovaMantis();
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

class CWE89_P07_V1_NovaMantisSource {
    public String loadNovaMantis() {
        String data;
        data = System.getenv("NOVA_MANTIS_FILTER");
        return data;
    }
}
